-- orders table backup taken 2025-03-02 before tokenisation migration (fictional)
CREATE TABLE orders (id INT, customer VARCHAR(40), cc_number VARCHAR(19), cc_exp CHAR(7), total DECIMAL(9,2));
INSERT INTO orders VALUES (90114,'cust-20871','6011000990139424','2027-03',88.20);
INSERT INTO orders VALUES (90115,'cust-20872','4111111111111111','2026-12',41.00);
INSERT INTO orders VALUES (90116,'cust-20873','5105-1051-0510-5100','2028-06',129.95);
