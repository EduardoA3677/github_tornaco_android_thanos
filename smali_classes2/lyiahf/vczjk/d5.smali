.class public final synthetic Llyiahf/vczjk/d5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroid/os/Parcelable;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/d5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/d5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/cc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;I)V
    .locals 0

    const/4 p5, 0x5

    iput p5, p0, Llyiahf/vczjk/d5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/w41;Llyiahf/vczjk/w41;Llyiahf/vczjk/ps9;Landroid/content/Context;)V
    .locals 1

    const/16 v0, 0xc

    iput v0, p0, Llyiahf/vczjk/d5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/d5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Ljava/lang/String;

    check-cast p2, Ljava/lang/String;

    const-string p1, "id"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/String;->hashCode()I

    move-result p1

    const v0, -0x545695b6

    const/4 v1, 0x1

    if-eq p1, v0, :cond_4

    const v0, -0x3b51a10d

    if-eq p1, v0, :cond_2

    const v0, -0x2f3174da

    if-eq p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const-string p1, "wechat"

    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/w41;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    goto :goto_0

    :cond_2
    const-string p1, "paypal"

    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_3

    goto :goto_0

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/ps9;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    const-string p2, "https://www.paypal.me/tornaco"

    iget-object v0, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Landroid/content/Context;

    invoke-static {v0, p1, p2}, Lgithub/tornaco/android/thanos/core/util/ClipboardUtils;->copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/kh6;->OooOOO0(Landroid/content/Context;)V

    goto :goto_0

    :cond_4
    const-string p1, "alipay"

    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_5

    goto :goto_0

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/w41;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/i48;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/j28;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/cm4;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/kh6;->OooO0O0(Llyiahf/vczjk/j28;Llyiahf/vczjk/cm4;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/i48;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Lnow/fortuitous/thanos/process/v2/RunningProcessState;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/ls1;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oy7;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/mt6;->OooO0OO(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/ls1;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Ltornaco/apps/thanox/running/RunningProcessState;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/ks1;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/ny7;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ht6;->OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ks1;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_3
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/ls1;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/oy7;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/mt6;->OooO0o0(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/ls1;Llyiahf/vczjk/oy7;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_4
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/ks1;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/ny7;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Ltornaco/apps/thanox/running/RunningAppState;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ht6;->OooO0Oo(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/ks1;Llyiahf/vczjk/ny7;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_5
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/rz5;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Ljava/lang/String;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOOO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Ljava/lang/String;Llyiahf/vczjk/rz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_6
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/cc6;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/mc4;->OooOO0(Llyiahf/vczjk/cc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_7
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Ljava/lang/String;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/os9;->OooOO0o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_8
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0xc01

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/iv3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/kl5;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/hv3;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/l4a;->OooO0Oo(Llyiahf/vczjk/iv3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/hv3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_9
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/hv3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/iv3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/l4a;->OooO0OO(Llyiahf/vczjk/iv3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/hv3;Ljava/lang/Throwable;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_a
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0xdb7

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/a91;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/kl5;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/jp8;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_b
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOo0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOO:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ow5;

    iget-object p1, p0, Llyiahf/vczjk/d5;->OooOOOO:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/t51;->OooO0oO(Llyiahf/vczjk/ow5;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
