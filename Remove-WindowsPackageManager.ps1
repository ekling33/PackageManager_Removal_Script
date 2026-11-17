SELECT name,
       CASE WHEN encryptid IS NULL THEN 'NOT encrypted' ELSE 'Encrypted' END AS encryption
FROM dbo.BPAWorkQueue
ORDER BY encryption, name;
