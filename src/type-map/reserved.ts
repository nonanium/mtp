import reserved from "../../type-map/reserved.json" with { type: "json" };

export const FIRST_USER_TYPE_ID = reserved.firstUserTypeId;
export const RESERVED_COMMUNICATION_TYPES = reserved.communication.map(
  ({ name }) => name,
);
export const RESERVED_DATA_TYPES = reserved.data.map(({ name }) => name);
export const RESERVED_COMMUNICATION_TYPE_IDS = Object.fromEntries(
  reserved.communication.map(({ name, id }) => [name, id]),
);
export const RESERVED_DATA_TYPE_IDS = Object.fromEntries(
  reserved.data.map(({ name, id }) => [name, id]),
);
