.class public final synthetic Llyiahf/vczjk/v47;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/up8;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a57;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a57;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/v47;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/v47;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-static {v0, p1}, Llyiahf/vczjk/a57;->OooOo0(Llyiahf/vczjk/a57;Llyiahf/vczjk/kp8;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-static {v0, p1}, Llyiahf/vczjk/a57;->Oooo000(Llyiahf/vczjk/a57;Llyiahf/vczjk/kp8;)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-static {v0, p1}, Llyiahf/vczjk/a57;->OooOoo0(Llyiahf/vczjk/a57;Llyiahf/vczjk/kp8;)V

    return-void

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-static {v0, p1}, Llyiahf/vczjk/a57;->OooOoO0(Llyiahf/vczjk/a57;Llyiahf/vczjk/kp8;)V

    return-void

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-static {v0, p1}, Llyiahf/vczjk/a57;->OooOo0o(Llyiahf/vczjk/a57;Llyiahf/vczjk/kp8;)V

    return-void

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    iget-object v0, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    const-string v1, "android_id"

    invoke-static {v0, v1}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "getString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/Optional;->ofNullable(Ljava/lang/Object;)Lgithub/tornaco/android/thanos/core/util/Optional;

    move-result-object v0

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/NPEFixing;->emptyString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/util/Optional;->orElse(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    iget-object v0, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Landroid/telephony/SubscriptionManager;->from(Landroid/content/Context;)Landroid/telephony/SubscriptionManager;

    move-result-object v0

    invoke-virtual {v0}, Landroid/telephony/SubscriptionManager;->getActiveSubscriptionInfoList()Ljava/util/List;

    move-result-object v0

    const-string v1, "getActiveSubscriptionInfoList(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    new-array v2, v1, [Landroid/telephony/SubscriptionInfo;

    invoke-interface {v0, v2}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/Optional;->ofNullable(Ljava/lang/Object;)Lgithub/tornaco/android/thanos/core/util/Optional;

    move-result-object v0

    new-array v1, v1, [Landroid/telephony/SubscriptionInfo;

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/util/Optional;->orElse(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/v47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-static {v0, p1}, Llyiahf/vczjk/a57;->OooOooo(Llyiahf/vczjk/a57;Llyiahf/vczjk/kp8;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
