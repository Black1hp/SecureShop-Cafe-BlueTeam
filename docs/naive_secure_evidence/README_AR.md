# أدلة Naive vs Secure — SecureShop Café

دي **حزمة أدلة إضافية** لمشروع CET431، مش نسخة بديلة من تطبيق الكافيه.

## الملفات
- `test_naive_concepts.py`: 12 مثالًا تعليميًا ضعيفًا في الذاكرة، بدون سيرفر أو قاعدة بيانات حقيقية.
- `naive_demo.log`: نتائج تشغيل الأمثلة (12/12).
- `secure_app_tests.log`: نتائج اختبارات التطبيق الفعلي (35/35).
- `NAIVE_VS_SECURE_EVIDENCE.md`: جدول المقارنة ومكان كل اختبار وتحذيرات استخدام الدليل.

## تشغيل الأمثلة
بعد فك الضغط افتحي Terminal داخل فولدر الأدلة:

```bash
python3 -m unittest -v test_naive_concepts
```

## إرسال الأدلة على GitHub
انسخي فولدر الأدلة إلى داخل مشروعك في `docs/naive_secure_evidence/` ثم شغّلي:

```bash
cd "$HOME/Desktop/SecureShop_Cafe_v2 2"
git status --short
git add docs/naive_secure_evidence
git diff --cached --stat
git commit -m "Document isolated naive vs secure Blue Team self-test evidence"
git push origin main
```

**مهم:** تقرير الأمثلة مش دليل إن عندنا نسخة ضعيفة حقيقية للموقع. لو الدكتور عايز Screenshot من هجوم على تطبيق ضعيف كامل، ده لسه محتاج تجربة منفصلة. وما ترفعيش قاعدة بيانات حساباتك أو أي أسرار.
