.class public final synthetic Llyiahf/vczjk/mea;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/mea;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/mea;->OooOOO:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/mea;->OooOOO:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;

    iget v1, p0, Llyiahf/vczjk/mea;->OooOOO0:I

    check-cast p1, Ljava/lang/String;

    packed-switch v1, :pswitch_data_0

    sget v1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO:I

    const-string v1, "pin"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockPin()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_0
    sget v1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO:I

    const-string v1, "it"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockPattern()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {v0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOooo()V

    goto :goto_0

    :cond_0
    iget p1, v0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0O:I

    const/4 v1, 0x3

    if-le p1, v1, :cond_1

    invoke-virtual {v0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOooO()V

    :cond_1
    iget p1, v0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0O:I

    add-int/lit8 p1, p1, 0x1

    iput p1, v0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0O:I

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
