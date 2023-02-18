package com.travelunion.flutter_biometrics;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.fragment.app.FragmentActivity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import androidx.biometric.BiometricPrompt.CryptoObject;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.embedding.engine.plugins.activity.ActivityAware;
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

public class FlutterBiometricsPlugin implements MethodCallHandler, FlutterPlugin, ActivityAware {
  protected static String KEY_ALIAS = "biometric_key";
  protected static String KEYSTORE = "AndroidKeyStore";
  private MethodChannel channel;
  private Activity activity;
  private final AtomicBoolean authInProgress = new AtomicBoolean(false);

  public FlutterBiometricsPlugin() {
  }

  @Override
  public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
    channel = new MethodChannel(flutterPluginBinding.getBinaryMessenger(), Constants.channel);
  }

  @Override
  public void onDetachedFromEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {

  }

  @Override
  public void onAttachedToActivity(@NonNull ActivityPluginBinding activityPluginBinding) {
    activity = activityPluginBinding.getActivity();
    channel.setMethodCallHandler(this);
  }

  @Override
  public void onDetachedFromActivityForConfigChanges() {
    activity = null;
  }

  @Override
  public void onReattachedToActivityForConfigChanges(@NonNull ActivityPluginBinding activityPluginBinding) {
    activity = activityPluginBinding.getActivity();
  }

  @Override
  public void onDetachedFromActivity() {
    activity = null;
    channel.setMethodCallHandler(null);
  }

  public static void registerWith(Registrar registrar) {
    final MethodChannel channel = new MethodChannel(registrar.messenger(), Constants.channel);
    FlutterBiometricsPlugin plugin = new FlutterBiometricsPlugin();
    plugin.activity = registrar.activity();
    channel.setMethodCallHandler(plugin);
  }


  @Override
  public void onMethodCall(MethodCall call, final Result result) {
    if (call.method.equals(Constants.MethodNames.createKeys)) {
      createKeys(call, result);
    } else if (call.method.equals(Constants.MethodNames.sign)) {
      sign(call, result);
    } else if( call.method.equals(Constants.MethodNames.decrypt)) {
      decrypt(call, result);
    } else if (call.method.equals(Constants.MethodNames.availableBiometricTypes)) {
      availableBiometricTypes(result);
    } else if( call.method.equals(Constants.MethodNames.deleteKeys)) {
      deleteBiometricKey(result);
    } else {
      result.notImplemented();
    }
  }

  protected void createKeys(MethodCall call, final Result result) {
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      if (!keyStore.containsAlias(KEY_ALIAS)) {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
                KEYSTORE);

        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT |
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY).
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512).setUserAuthenticationRequired(true).build());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        result.success(getEncodedPublicKey(keyPair.getPublic()));
      } else {

        result.success(getEncodedPublicKey(keyStore.getCertificate(KEY_ALIAS).getPublicKey()));
      }
    } catch (Exception e) {
      result.error("create_keys_error", "Error generating public private keys: " + e.getMessage(), null);
    }
  }

  protected void decrypt(final MethodCall call, final Result result) {
    if (!authInProgress.compareAndSet(false, true)) {
      result.error("auth_in_progress", "Authentication in progress", null);
      return;
    }

    if (activity == null || activity.isFinishing()) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("no_activity", "local_auth plugin requires a foreground activity", null);
      }
      return;
    }

    if (!(activity instanceof FragmentActivity)) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("no_fragment_activity", "local_auth plugin requires activity to be a FragmentActivity.", null);
      }
      return;
    }

    if (call.argument("ciphertext") == null) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("ciphertext_not_provided", "You need to provide a ciphertext to decrypt", null);
      }
      return;
    }

    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);

      PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256",
              "MGF1",
              MGF1ParameterSpec.SHA1,
              PSource.PSpecified.DEFAULT);
      cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
      CryptoObject cryptoObject = new CryptoObject(cipher);

      AuthenticationHelper authenticationHelper = new AuthenticationHelper((FragmentActivity) activity, call,
              cryptoObject, new AuthenticationHelper.AuthCompletionHandler() {
        @Override
        public void onSuccess(CryptoObject cryptoObject) {
          if (authInProgress.compareAndSet(true, false)) {
            try {
              Cipher cipher = cryptoObject.getCipher();
              byte[] decoded = Base64.decode((String) call.argument("ciphertext"), Base64.DEFAULT | Base64.URL_SAFE | Base64.NO_WRAP);
              byte[] plaintext = cipher.doFinal(decoded);
              String plaintextString = Base64.encodeToString(plaintext, Base64.DEFAULT | Base64.URL_SAFE | Base64.NO_WRAP);
              result.success(plaintextString);
            } catch (Exception e) {
              result.error("decrypt_error", "Error decrypting ciphertext: " + e.getMessage(), null);
            }
          }
        }

        @Override
        public void onFailure() {
          if (authInProgress.compareAndSet(true, false)) {
            result.success(false);
          }
        }

        @Override
        public void onError(String code, String error) {
          if (authInProgress.compareAndSet(true, false)) {
            result.error(code, error, null);
          }
        }
      });
      authenticationHelper.authenticate();
    } catch(KeyPermanentlyInvalidatedException invalidatedException) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("biometrics_invalidated", "Biometric keys are invalidated: " + invalidatedException.getMessage(), null);
      }
    } catch (Exception e) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("sign_error_key", "Error retrieving keys: " + e.getMessage(), null);
      }
    }
  }

  protected void sign(final MethodCall call, final Result result) {
    if (!authInProgress.compareAndSet(false, true)) {
      result.error("auth_in_progress", "Authentication in progress", null);
      return;
    }

    if (activity == null || activity.isFinishing()) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("no_activity", "local_auth plugin requires a foreground activity", null);
      }
      return;
    }

    if (!(activity instanceof FragmentActivity)) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("no_fragment_activity", "local_auth plugin requires activity to be a FragmentActivity.", null);
      }
      return;
    }

    if (call.argument("payload") == null) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("payload_not_provided", "You need to provide payload to sign", null);
      }
      return;
    }

    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);

      PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateKey);

      CryptoObject cryptoObject = new CryptoObject(signature);

      AuthenticationHelper authenticationHelper = new AuthenticationHelper((FragmentActivity) activity, call,
          cryptoObject, new AuthenticationHelper.AuthCompletionHandler() {
            @Override
            public void onSuccess(CryptoObject cryptoObject) {
              if (authInProgress.compareAndSet(true, false)) {
                try {
                  Signature cryptoSignature = cryptoObject.getSignature();
                  byte[] decoded = Base64.decode((String) call.argument("payload"), Base64.DEFAULT | Base64.URL_SAFE | Base64.NO_WRAP);
                  cryptoSignature.update(decoded);
                  byte[] signed = cryptoSignature.sign();
                  String signedString = Base64.encodeToString(signed, Base64.DEFAULT | Base64.URL_SAFE | Base64.NO_WRAP);
                  signedString = signedString.replaceAll("\r", "").replaceAll("\n", "");
                  result.success(signedString);
                } catch (Exception e) {
                  result.error("sign_error", "Error generating signing payload: " + e.getMessage(), null);
                }
              }
            }

            @Override
            public void onFailure() {
              if (authInProgress.compareAndSet(true, false)) {
                result.success(false);
              }
            }

            @Override
            public void onError(String code, String error) {
              if (authInProgress.compareAndSet(true, false)) {
                result.error(code, error, null);
              }
            }
          });
      authenticationHelper.authenticate();
    } catch(KeyPermanentlyInvalidatedException invalidatedException) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("biometrics_invalidated", "Biometric keys are invalidated: " + invalidatedException.getMessage(), null);
      }
    } catch (Exception e) {
      if (authInProgress.compareAndSet(true, false)) {
        result.error("sign_error_key", "Error retrieving keys: " + e.getMessage(), null);
      }
    }
  }

  protected void availableBiometricTypes(final Result result) {
    try {
      if (activity == null || activity.isFinishing()) {
        result.error("no_activity", "local_auth plugin requires a foreground activity", null);
        return;
      }
      ArrayList<String> biometrics = new ArrayList<String>();
      PackageManager packageManager = activity.getPackageManager();
      if (Build.VERSION.SDK_INT >= 23) {
        if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
          biometrics.add(Constants.BiometricsType.fingerprint);
        }
      }
      if (Build.VERSION.SDK_INT >= 29) {
        if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
          biometrics.add(Constants.BiometricsType.faceId);
        }
        if (packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
          biometrics.add(Constants.BiometricsType.iris);
        }
      }
      result.success(biometrics);
    } catch (Exception e) {
      result.error("no_biometrics_available", e.getMessage(), null);
    }
  }

  protected String getEncodedPublicKey(PublicKey publicKey) {
    byte[] encodedPublicKey = publicKey.getEncoded();
    String publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT);
    return publicKeyString.replaceAll("\r", "").replaceAll("\n", "");
  }

  protected void deleteBiometricKey(final Result result) {
    try {
      KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
      keyStore.load(null);

      keyStore.deleteEntry(KEY_ALIAS);
      result.success(true);
    } catch (Exception e) {
      result.error("delete_biometric_key_error", e.getMessage(), null);
    }
  }
}
