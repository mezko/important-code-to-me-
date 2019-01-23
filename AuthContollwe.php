<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\User;

use App\Model\level;
use JWTAuth;
use Validator, Hash,Storage;
use App\Model\user_pass;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware(
         'auth:api',  
        ['except' => 
        ['login','register','check_code','send_code_reset_password'
        ,'reset_password'
        ,'get_all_user'
        ,'getUserWithLastLevel'
        ,'check_code_reset_password'
        ,'destroy'
        ,'cancel_trached'
        ,'trached'
        ,'get_user_levels'
        ,'Admin_login'
        ,'edit_admin_password']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
   public function get_all_user(){
    $input=Request()->all();
    if(isset($input['filter']) &&$input['filter']==1)
{
     

          $level=level::orderBy('id','desc')->first();
   
            $user=user_pass::with(['user'=>function($query){
                $query->withTrashed();
                $query->where('Admin','0');
            }])->where('level_id',$level['id'])->paginate(10);  
             
}
    else if(isset($input['filter']) &&$input['filter']==0){
       $user=User::with(['user_pass'=>function($query){
        $query->orderBy('level_id','desc');
        $query->first();
        $query->with('level');
    }])->withTrashed()->where('Admin','0')->paginate(10);
    }
    return Response()->json(['users'=>$user],200);
   }
 public function get_user_levels($id)
 {
    $user= User::with(['user_pass'=>function($query){
        $query->orderBy('level_id','desc');
        $query->with(['level'=>function($query){
            $query->with('exam');
        }]);
    }])->withTrashed()->where('id',$id)->get();
    return Response()->json(['user'=>$user],200);
 }
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
   
    public function register(Request $request)
    {
     $rand=$request->rand=rand(1000,10000);   
      $credentials = $request->only('name','full_name','phone','email','image','password','token_id','rand');

      $rules = [
          'phone' => 'required|unique:users',
          'password' => 'required',
          'token_id'=>'required',
          'name'=>'required',
          'full_name'=>'required',
          'email'=>'required|email|unique:users',
        //  'rand'=>'required'
          //'image'=>'required'

      ];
    
      $validator = Validator::make($credentials, $rules);
      if($validator->fails()) {
          return response()->json(['success'=> false, 'error'=> $validator->messages()],401);
      }

      $phone = $request->phone;
      $password = $request->password;
      $token_id=$request->token_id;
      $name=$request->name;

      $full_name=$request->full_name;

      $email=$request->email;
      $image=$request->image;
      if(isset($image)){
       
        
                $image_name = 'media-'.rand(10,100) . date('mdYhis') . '.' . pathinfo($image->getClientOriginalName() , PATHINFO_EXTENSION);
                $image_path = 'public/image/';
                Storage::disk('local')->putFileAs($image_path, $image, $image_name);
                $image_path = Storage::disk('local')->url($image_path . $image_name);
                $image='/storage/image/'.$image_name;

      }
    
      $user = User::create(['phone' => $phone, 'password' => Hash::make($password),'name'=>$name,'full_name'=>$full_name,'image'=>$image,'email'=>$email,'token_id'=>$token_id,'generated_code'=>$rand]);
      
    return $this->SendSMSWithRand($phone, $rand);
    }
    public function SendSMSWithRand($phone, $rand)
    {
    	
        $fields = array(
            "AppSid" => "vGkfaWIOZOU2OzJn7liuXU39atTY",
            "Recipient" => $phone,
            "Body" => $rand
        );
        $fields = json_encode($fields);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://api.unifonic.com/rest/Messages/Send");
//        curl_setopt($ch, CURLOPT_URL, "https://private-anon-46b550cebd-unifonic.apiary-proxy.com/rest/Verify/VerifyNumber");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        curl_setopt($ch, CURLOPT_POST, TRUE);
//        curl_setopt($ch, CURLOPT_POSTFIELDS, "AppSid=vGkfaWIOZOU2OzJn7liuXU39atTY?Recipient=$phone&Body=$rand&SenderID=SHL");
        curl_setopt($ch, CURLOPT_POSTFIELDS, "AppSid=vGkfaWIOZOU2OzJn7liuXU39atTY&Recipient=$phone&Body=$rand&SenderID=muthaber");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            "Content-Type: application/x-www-form-urlencoded"
        ));
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
       
    }

    public function check_code(Request $request){
        $input=Request()->all();
        $user=User::where('phone',$input['phone'])->first();
        if($input['rand']== $user['generated_code']){
            User::where('phone',$input['phone'])->update(['type'=>1]);
            return $this->login($request);
        }
        else{
        return response()->json(['error' => 'Unauthorized'], 401);
        }


    }
    

    public function send_code_reset_password(){
        $input = Request()->all();
        $check=User::where('phone',$input['phone'])->withTrashed()->get();

        if(count($check) > 0){
          if($check[0]['deleted_at'] == null ){
            $rand=rand(1000,10000);
            $phone=$check[0]['phone'];
            User::where('phone',$input['phone'])->update(['generated_code'=>$rand,'type'=>0]);
            $output=User::where('phone',$input['phone'])->first();
          //  $output['auth']="need verification code";
            return $this->SendSMSWithRand($phone,$rand);
          }else{
              return response()->json(['error' => 'you are banned!'], 400);
          }
        }else{
            return ['error'=>'??? ??????? ???? ?????? ????? '];
        }

    }
     
      public function check_code_reset_password(Request $request){
        $input=Request()->all();
        $user=User::where('phone',$input['phone'])->first();
        if($input['rand']== $user['generated_code']){
            User::where('phone',$input['phone'])->update(['type'=>1]);
                return response()->json(['msg' => 'successfull'], 200);
                }
        else{
        return response()->json(['error' => 'Unauthorized'], 401);
        }


    }

    public function reset_password(Request $request){
        $input = Request()->all();
   
         $check=User::where('phone',$input['phone'])
        ->where('type',1)
         ->get();


         if(count($check) > 0){
            User::where('phone',$input['phone'])->update(['password'=>Hash::make($input['password'])]);
            return $this->login($request);

         }else{
        return response()->json(['error' => 'Unauthorized'], 401);
         }

        }






    public function login(Request $request)
    {
        
       $user=User::where('phone',$request->phone)->withTrashed()->first();
       if($user['deleted_at'] == NULL ){
        if($user['type'] > 0){
        $credentials = $request->only('phone','password');
        if ($token = JWTAuth::attempt($credentials)) {
            User::where('phone',$request->phone)->update(['token_id'=>$request->token_id]);

            return $this->respondWithToken($token);
        }
    }
  }else{
            return response()->json(['error' => 'you are banned!'], 400);

  }
        return response()->json(['error' => 'Unauthorized'], 401);
    }

 public function Admin_login(Request $request)
    {
        
       $user=User::where('email',$request->email)->first();

        if($user['Admin'] == 1){
        $credentials = $request->only('email','password');
        if ($token = JWTAuth::attempt($credentials)) {

            return $this->respondWithToken($token);
        }
    }
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        $user=auth()->user();
        $user_pass=user_pass::where('user_id',$user['id'])->where('level_id','!=',null)->count();
        if($user_pass > 0){
        $end_user_pass = user_pass::where('user_id',$user['id'])->orderBy('id','desc')->first();

        if($end_user_pass['level_id'] != null)
        $level_id=level::where('id','>',$end_user_pass['level_id'])->min('id');

        $Level_duration=user_pass::where('user_id',$user['id'])->where('level_id',$end_user_pass['level_id'])->first();
                 if($end_user_pass['pass'] == 0 || $Level_duration['level_start_date'] != null){
        	                return ['user'=>$user,'placementExamPass'=>1,'current_level_id'=>$end_user_pass['level_id'],'level_start_date'=>$Level_duration['level_start_date'],'level_end_date'=>$Level_duration['level_end_date']];

        	            }else{
        	                return ['user'=>$user,'placementExamPass'=>1,'current_level_id'=>$level_id,'level_start_date'=>$Level_duration['level_start_date'],'level_end_date'=>$Level_duration['level_end_date']];

        	            }
        }
        else{
              $user_pas=user_pass::where('user_id',$user['id'])->where('exam_start_date','!=',null)->count();
              if($user_pas >0){
                     return ['user'=>$user,'placementExamPass'=>1,'current_level_id'=>0,'level_start_date'=>'null','level_end_date'=>'null'];

              }else{
                 return ['user'=>$user,'placementExamPass'=>0,'current_level_id'=>0,'level_start_date'=>'null','level_end_date'=>'null'];

              }


        }

    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }
    public function destroy($id){
        User::where('id',$id)->forceDelete();
        return Response()->json(['user'=>'deleted'],200);
    }
    public function trached($id){
        User::where('id',$id)->delete();
        return Response()->json(['user'=>'deleted'],200);
    }
    public function cancel_trached($id){
        User::where('id',$id)->restore();
        return Response()->json(['user'=>'deleted'],200);
    }
      public function edit_admin_password(){
        $input = Request()->all();
       $user=User::where('Admin','1')->first();
       if(Hash::check($input['old_password'], $user['password'])){
         $user->update(['password'=>Hash::make($input['new_password'])]);
         return ['state'=>202];
       }else{
         return Response()->json(['message'=>"your old password don't match "],400);
       }
    }
  
}