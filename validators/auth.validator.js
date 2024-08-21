const { z } = require("zod")

const signupSchema = z.object({
    username: z
        .string({ required_error: "Name is require" })
        .trim()
        .min(3, { message: "name must be at lest of 3 chars" })
        .max(255, { message: "name must not be more then 255 chars" }),
        email: z
        .string({ required_error: "email is require" })
        .trim()
        .min(3, { message: "email must be at lest of 3 chars" })
        .max(255, { message: "email must not be more then 255 chars" }),
        phone: z
        .string({ required_error: "phone is require" })
        .trim()
        .min(10, { message: "phone must be at lest of 10 chars" })
        .max(20, { message: "phone must not be more then 20 chars" }),
        password: z
        .string({ required_error: "password is require" })
        .trim()
        .min(5, { message: "password must be at lest of 5 chars" })
        .max(1024, { message: "password must not be more then 1024 chars" }),
        usertype: z
        .string({ required_error: "usertype is require" })
        .trim()
        .min(8, { message: "usertype must be at lest of 8 chars" })
        .max(255, { message: "usertype must not be more then 255 chars" }),
});
module.exports = signupSchema;
