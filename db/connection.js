import consola from "consola";
import { connect } from "mongoose";
import dotenv from "dotenv";
dotenv.config();

export const startApp = async (app) => {
    try {
      await connect(process.env.MONGO_URI);
      consola.success({
        message: `Successfully connected with database`,
        badge: true,
      });
      app.listen(process.env.PORT, () =>
        consola.success({
          message: `Server started on port ${process.env.PORT}`,
          badge: true,
        })
      );
    } catch (err) {
      consola.error({
        message: `Connection terminated \n ${err}`,
        badge: true,
      });
    }
  };