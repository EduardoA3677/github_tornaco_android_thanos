.class public final synthetic Llyiahf/vczjk/nea;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/nea;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nea;->OooOOO:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/nea;->OooOOO:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;

    iget v2, p0, Llyiahf/vczjk/nea;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    sget v0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO:I

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget v2, v1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0O:I

    add-int/lit8 v2, v2, 0x1

    iput v2, v1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0O:I

    const/4 v3, 0x3

    if-le v2, v3, :cond_0

    invoke-virtual {v1}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOooO()V

    :cond_0
    return-object v0

    :pswitch_1
    sget v2, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO:I

    invoke-virtual {v1}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOooo()V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
