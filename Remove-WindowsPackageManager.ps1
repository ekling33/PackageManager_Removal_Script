-- Version and edition
SELECT @@VERSION AS version, SERVERPROPERTY('Edition') AS edition;

-- TDE status for every database on the server
SELECT d.name,
       d.is_encrypted,
       CASE k.encryption_state
            WHEN 0 THEN 'No key'
            WHEN 1 THEN 'Unencrypted'
            WHEN 2 THEN 'Encryption in progress'
            WHEN 3 THEN 'Encrypted'
            WHEN 4 THEN 'Key change in progress'
            WHEN 5 THEN 'Decryption in progress'
            WHEN 6 THEN 'Protection change in progress'
            ELSE 'Not set up'
       END AS tde_state,
       k.key_algorithm,
       k.key_length
FROM sys.databases d
LEFT JOIN sys.dm_database_encryption_keys k
       ON k.database_id = d.database_id
ORDER BY d.name;
