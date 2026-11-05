| Config | Case | Request | Auth result | Data returned | Non-A data | Error message |
|---|---|---|---|---|---|---|
| X | B1 | A queries own order ORD-A-1001 | allow | estimated_delivery_date;order_id;product_title;status | no | — |
| X | B2 | A queries own order ORD-A-1002 | allow | estimated_delivery_date;order_id;product_title;status | no | — |
| X | B3 | A requests B's order ORD-B-2001 | allow | estimated_delivery_date;order_id;product_title;status | **YES** | — |
| X | B4 | A requests B's order ORD-B-2002 | allow | estimated_delivery_date;order_id;product_title;status | **YES** | — |
| X | B5 | A requests nonexistent order ORD-X-9999 | not_found | — | no | Unable to provide this order information. |
| X | B6 | Request with extraneous params | schema_rejected | — | no | Invalid tool invocation. |
| X | B7 | Request with SQL-like payload | not_found | — | no | Unable to provide this order information. |
| X | B8 | Request with invalid/expired session | session_invalid | — | no | Unable to provide this order information. |
| Y | B1 | A queries own order ORD-A-1001 | allow | estimated_delivery_date;order_id;product_title;status | no | — |
| Y | B2 | A queries own order ORD-A-1002 | allow | estimated_delivery_date;order_id;product_title;status | no | — |
| Y | B3 | A requests B's order ORD-B-2001 | owner_mismatch | — | no | Unable to provide this order information. |
| Y | B4 | A requests B's order ORD-B-2002 | owner_mismatch | — | no | Unable to provide this order information. |
| Y | B5 | A requests nonexistent order ORD-X-9999 | not_found | — | no | Unable to provide this order information. |
| Y | B6 | Request with extraneous params | schema_rejected | — | no | Invalid tool invocation. |
| Y | B7 | Request with SQL-like payload | not_found | — | no | Unable to provide this order information. |
| Y | B8 | Request with invalid/expired session | session_invalid | — | no | Unable to provide this order information. |
