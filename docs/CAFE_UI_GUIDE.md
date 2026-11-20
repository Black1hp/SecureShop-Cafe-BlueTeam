# SecureShop Cafe UI guide

## Design

Cream background, dark espresso headings and buttons, caramel accents, responsive four-column catalogue, hero banner and CSS product art.

## Where to edit

- `app.py` variable `CSS`: all styles and media queries.
- `app.py` function `page`: shared header, menu and footer.
- `app.py` function `route_get`: landing catalogue, category filters and product detail layout.
- `app.py` dictionary `PRODUCT_LOOK`: card icons, theme and category for each catalogue item.
- `app.py` function `init_db`: 12 starter products, prices in cents, and stock.

## Product data caveat

The `init_db` seed only runs on an empty products table. Preserve existing data when upgrading. The demo catalogue uses virtual dollar prices because the original SecureShop checkout formats dollars; you can switch display currency separately without changing the meaning of stored prices.

## Testing

Run `python3 -m unittest discover -s tests -v`. For visual review, open `http://localhost:8000` on desktop and mobile sizes.
