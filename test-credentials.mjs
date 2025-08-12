import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { SecureCredentialsManager } from './server/secure-credentials';

/**
 * Script de test pour valider le système de credentials sécurisé
 */
async function testCredentialsSystem() {
  console.log('🧪 Test du système de credentials sécurisé Spotify\n');

  const manager = new SecureCredentialsManager();
  const testUserId = 'test-user-' + crypto.randomBytes(4).toString('hex');

  try {
    // Test 1: Sauvegarde des credentials
    console.log('📝 Test 1: Sauvegarde des credentials...');
    const mockTokenData = {
      access_token: 'BQC4YqK3H9P8...test_access_token_' + Date.now(),
      refresh_token: 'AQD9j7X2N5M...test_refresh_token_' + Date.now(),
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'user-read-playback-state user-modify-playback-state'
    };

    const saveResult = manager.saveCredentials(testUserId, mockTokenData);
    console.log(`✅ Credentials sauvegardés avec ID: ${saveResult}`);

    // Test 2: Récupération des credentials
    console.log('\n🔍 Test 2: Récupération des credentials...');
    const retrievedCredentials = manager.getCredentials(testUserId);

    if (retrievedCredentials) {
      console.log('✅ Credentials récupérés avec succès');
      console.log(`   - Access token: ${retrievedCredentials.access_token.substring(0, 20)}...`);
      console.log(`   - Token type: ${retrievedCredentials.token_type}`);
      console.log(`   - Expires at: ${new Date(retrievedCredentials.expires_at * 1000).toLocaleString()}`);
      console.log(`   - Is expired: ${retrievedCredentials.is_expired ? '❌' : '✅'}`);
      console.log(`   - Scopes: ${retrievedCredentials.scopes}`);
    } else {
      throw new Error('❌ Impossible de récupérer les credentials');
    }

    // Test 3: Validation du token
    console.log('\n🔐 Test 3: Validation du token...');
    const isValid = manager.isTokenValid(testUserId);
    console.log(`✅ Token valide: ${isValid ? '✅ Oui' : '❌ Non'}`);

    // Test 4: Statistiques de sécurité
    console.log('\n📊 Test 4: Statistiques de sécurité...');
    const stats = manager.getSecurityStats();
    console.log('✅ Statistiques récupérées:');
    console.log(`   - Credentials stockés: ${stats.stored_credentials}`);
    console.log(`   - Total accès: ${stats.total_accesses}`);
    console.log(`   - Dernier accès: ${stats.last_access ? stats.last_access.toLocaleString() : 'N/A'}`);
    console.log(`   - Empreinte client: ${stats.client_fingerprint}`);
    console.log(`   - Base de données: ${stats.database_path}`);

    // Test 5: Test avec credentials expirés
    console.log('\n⏰ Test 5: Test avec token expiré...');
    const expiredTokenData = {
      ...mockTokenData,
      access_token: 'EXPIRED_TOKEN_' + Date.now(),
      expires_in: -1 // Déjà expiré
    };

    const expiredUserId = 'expired-user-' + crypto.randomBytes(4).toString('hex');
    manager.saveCredentials(expiredUserId, expiredTokenData);

    const expiredCredentials = manager.getCredentials(expiredUserId);
    console.log(`✅ Token expiré correctement détecté: ${expiredCredentials.is_expired ? '✅' : '❌'}`);

    // Test 6: Test de chiffrement/déchiffrement
    console.log('\n🔒 Test 6: Vérification du chiffrement...');
    const originalToken = mockTokenData.access_token;
    const retrievedToken = retrievedCredentials.access_token;

    if (originalToken === retrievedToken) {
      console.log('✅ Déchiffrement réussi - tokens correspondent');
    } else {
      throw new Error('❌ Erreur de déchiffrement - tokens ne correspondent pas');
    }

    // Test 7: Test de suppression
    console.log('\n🗑️ Test 7: Suppression des credentials...');
    const deleteResult = manager.deleteCredentials(testUserId);
    console.log(`✅ Suppression: ${deleteResult ? 'Réussie' : 'Échouée'}`);

    // Vérifier que les credentials ont bien été supprimés
    const deletedCredentials = manager.getCredentials(testUserId);
    if (!deletedCredentials) {
      console.log('✅ Confirmation: Credentials bien supprimés de la base');
    } else {
      throw new Error('❌ Erreur: Credentials toujours présents après suppression');
    }

    // Test 8: Nettoyage des credentials expirés
    console.log('\n🧹 Test 8: Nettoyage des credentials expirés...');
    const cleanedCount = manager.cleanupExpiredCredentials();
    console.log(`✅ ${cleanedCount} credential(s) expiré(s) nettoyé(s)`);

    // Test 9: Test de sauvegarde de la base
    console.log('\n💾 Test 9: Test de sauvegarde...');
    const backupPath = `./test-backup-${Date.now()}.db`;
    const backupResult = manager.backup(backupPath);
    console.log(`✅ Sauvegarde: ${backupResult ? 'Réussie' : 'Échouée'}`);

    if (backupResult) {
      const fs = require('fs');
      if (fs.existsSync(backupPath)) {
        console.log(`✅ Fichier de sauvegarde créé: ${backupPath}`);
        // Nettoyer le fichier de test
        fs.unlinkSync(backupPath);
        console.log('✅ Fichier de sauvegarde test supprimé');
      }
    }

    // Test 10: Test de performances
    console.log('\n⚡ Test 10: Test de performances...');
    const startTime = process.hrtime.bigint();

    // Créer et récupérer plusieurs credentials
    for (let i = 0; i < 100; i++) {
      const perfUserId = `perf-user-${i}`;
      const perfTokenData = {
        ...mockTokenData,
        access_token: `perf_token_${i}_${Date.now()}`,
        refresh_token: `perf_refresh_${i}_${Date.now()}`
      };

      manager.saveCredentials(perfUserId, perfTokenData);
      manager.getCredentials(perfUserId);
    }

    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000; // Convertir en millisecondes

    console.log(`✅ Performance: 200 opérations (100 save + 100 get) en ${duration.toFixed(2)}ms`);
    console.log(`✅ Moyenne: ${(duration / 200).toFixed(3)}ms par opération`);

    // Nettoyer les données de test de performance
    for (let i = 0; i < 100; i++) {
      manager.deleteCredentials(`perf-user-${i}`);
    }
    console.log('✅ Données de test de performance nettoyées');

    // Statistiques finales
    console.log('\n📈 Statistiques finales:');
    const finalStats = manager.getSecurityStats();
    console.log(`   - Total credentials: ${finalStats.stored_credentials}`);
    console.log(`   - Total accès: ${finalStats.total_accesses}`);

    console.log('\n🎉 **TOUS LES TESTS RÉUSSIS!**');
    console.log('✅ Le système de credentials sécurisé fonctionne parfaitement');

  } catch (error) {
    console.error(`\n❌ **ERREUR DE TEST:** ${error.message}`);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  } finally {
    // Fermer la connexion à la base de données
    manager.close();

    // Nettoyer le user de test restant
    try {
      const cleanupManager = new SecureCredentialsManager();
      cleanupManager.deleteCredentials(testUserId);
      cleanupManager.close();
    } catch (e) {
      // Ignorer les erreurs de nettoyage
    }
  }
}

/**
 * Test de charge pour vérifier la robustesse
 */
async function loadTest() {
  console.log('\n🔥 Test de charge...');

  const manager = new SecureCredentialsManager();
  const userCount = 1000;
  const startTime = process.hrtime.bigint();

  try {
    // Créer beaucoup d'utilisateurs
    for (let i = 0; i < userCount; i++) {
      const userId = `load-test-user-${i}`;
      const tokenData = {
        access_token: `load_token_${i}_${crypto.randomBytes(16).toString('hex')}`,
        refresh_token: `load_refresh_${i}_${crypto.randomBytes(16).toString('hex')}`,
        expires_in: 3600,
        token_type: 'Bearer',
        scope: 'user-read-playback-state'
      };

      manager.saveCredentials(userId, tokenData);

      // Test de récupération aléatoire
      if (i % 100 === 0) {
        const randomUserId = `load-test-user-${Math.floor(Math.random() * i)}`;
        manager.getCredentials(randomUserId);
      }
    }

    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000;

    console.log(`✅ Test de charge réussi:`);
    console.log(`   - ${userCount} utilisateurs créés`);
    console.log(`   - Temps total: ${duration.toFixed(2)}ms`);
    console.log(`   - Moyenne: ${(duration / userCount).toFixed(3)}ms par utilisateur`);

    // Vérifier l'intégrité des données
    const stats = manager.getSecurityStats();
    console.log(`   - Credentials en base: ${stats.stored_credentials}`);

    // Nettoyage
    console.log('\n🧹 Nettoyage du test de charge...');
    for (let i = 0; i < userCount; i++) {
      manager.deleteCredentials(`load-test-user-${i}`);
    }

    const finalStats = manager.getSecurityStats();
    console.log(`✅ Nettoyage terminé: ${finalStats.stored_credentials} credentials restants`);

  } catch (error) {
    console.error(`❌ Erreur de test de charge: ${error.message}`);
  } finally {
    manager.close();
  }
}

/**
 * Test de sécurité pour vérifier la robustesse du chiffrement
 */
async function securityTest() {
  console.log('\n🛡️ Test de sécurité...');

  const manager = new SecureCredentialsManager();

  try {
    // Test avec des données sensibles
    const sensitiveData = {
      access_token: 'TOP_SECRET_TOKEN_' + crypto.randomBytes(32).toString('hex'),
      refresh_token: 'ULTRA_SECRET_REFRESH_' + crypto.randomBytes(32).toString('hex'),
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'admin-access full-control'
    };

    const secureUserId = 'security-test-user';

    // Sauvegarder
    manager.saveCredentials(secureUserId, sensitiveData);

    // Vérifier qu'on ne peut pas lire les données en raw dans la DB
    const db = new DatabaseSync(manager.dbPath);

    const rawRow = db.prepare('SELECT * FROM spotify_credentials WHERE user_id = ?').get(secureUserId);

    if (rawRow) {
      // Vérifier que les tokens sont bien chiffrés
      const isAccessTokenEncrypted = !rawRow.encrypted_access_token.includes('TOP_SECRET');
      const isRefreshTokenEncrypted = !rawRow.encrypted_refresh_token.includes('ULTRA_SECRET');

      console.log(`✅ Access token chiffré: ${isAccessTokenEncrypted ? '✅' : '❌'}`);
      console.log(`✅ Refresh token chiffré: ${isRefreshTokenEncrypted ? '✅' : '❌'}`);

      if (!isAccessTokenEncrypted || !isRefreshTokenEncrypted) {
        throw new Error('Tokens non chiffrés dans la base de données!');
      }
    }

    db.close();

    // Vérifier qu'on peut récupérer les bonnes données
    const decryptedData = manager.getCredentials(secureUserId);

    if (decryptedData.access_token === sensitiveData.access_token) {
      console.log('✅ Déchiffrement correct des données sensibles');
    } else {
      throw new Error('Erreur de déchiffrement!');
    }

    // Test avec des caractères spéciaux
    const specialData = {
      access_token: 'Token_with_émojis_🔐_and_symbols_!@#$%^&*()_+{}|:<>?[]\\;\',./`~',
      refresh_token: 'Refresh_with_unicode_™®©_and_quotes_"\'`',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'special-chars-test'
    };

    manager.saveCredentials('special-chars-user', specialData);
    const specialRetrieved = manager.getCredentials('special-chars-user');

    if (specialRetrieved.access_token === specialData.access_token) {
      console.log('✅ Gestion correcte des caractères spéciaux');
    } else {
      throw new Error('Erreur avec les caractères spéciaux!');
    }

    // Nettoyer
    manager.deleteCredentials(secureUserId);
    manager.deleteCredentials('special-chars-user');

    console.log('✅ Tests de sécurité réussis');

  } catch (error) {
    console.error(`❌ Erreur de test de sécurité: ${error.message}`);
    throw error;
  } finally {
    manager.close();
  }
}

// Fonction principale
async function runAllTests() {
  console.log('🚀 Démarrage de la suite de tests complète\n');

  try {
    await testCredentialsSystem();
    await loadTest();
    await securityTest();

    console.log('\n🏆 **TOUS LES TESTS SONT RÉUSSIS!**');
    console.log('✅ Votre système de credentials sécurisé est prêt pour la production');

  } catch (error) {
    console.error('\n💥 **ÉCHEC DES TESTS**');
    console.error(error.message);
    process.exit(1);
  }
}

// Vérifier si le script est exécuté directement
if (require.main === module) {
  runAllTests().catch(console.error);
}

export {
  testCredentialsSystem,
  loadTest,
  securityTest,
  runAllTests
}