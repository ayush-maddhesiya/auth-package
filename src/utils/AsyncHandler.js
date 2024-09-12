//make a async handler function , to use as with async await as wraper

export const asyncHandler = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (error) { 
    next(error);
  }
}