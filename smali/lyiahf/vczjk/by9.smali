.class public final synthetic Llyiahf/vczjk/by9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/by9;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    const/4 v0, 0x1

    const/4 v1, 0x0

    iget v2, p0, Llyiahf/vczjk/by9;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/patch/common/am/XAMS;->OooO00o(Ljava/lang/Object;)Lgithub/tornaco/android/thanos/core/process/ProcessRecord;

    move-result-object p1

    return-object p1

    :pswitch_0
    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/patch/common/am/XAMS;->OooO0OO(Ljava/lang/Object;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object p1

    return-object p1

    :pswitch_1
    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/patch/common/am/XAMS;->OooO0O0(Ljava/lang/Object;)Lgithub/tornaco/android/thanos/core/process/ProcessRecord;

    move-result-object p1

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/uj;

    const-string v2, "$this$AnimatedContent"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v2, 0x96

    const/4 v3, 0x0

    const/4 v4, 0x4

    invoke-static {v2, v2, v3, v4}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v4

    const/4 v5, 0x2

    invoke-static {v4, v5}, Llyiahf/vczjk/uo2;->OooO0OO(Llyiahf/vczjk/p13;I)Llyiahf/vczjk/fp2;

    move-result-object v4

    const/4 v6, 0x6

    invoke-static {v2, v1, v3, v6}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v1

    invoke-static {v1, v5}, Llyiahf/vczjk/uo2;->OooO0Oo(Llyiahf/vczjk/p13;I)Llyiahf/vczjk/dt2;

    move-result-object v1

    sget v2, Landroidx/compose/animation/OooO00o;->OooO0O0:I

    new-instance v2, Llyiahf/vczjk/fn1;

    invoke-direct {v2, v4, v1}, Llyiahf/vczjk/fn1;-><init>(Llyiahf/vczjk/fp2;Llyiahf/vczjk/dt2;)V

    new-instance v1, Llyiahf/vczjk/pka;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/pka;-><init>(Ljava/lang/Object;I)V

    invoke-static {v1, v0}, Landroidx/compose/animation/OooO00o;->OooO0OO(Llyiahf/vczjk/pka;I)Llyiahf/vczjk/br8;

    move-result-object p1

    iput-object p1, v2, Llyiahf/vczjk/fn1;->OooO0Oo:Llyiahf/vczjk/br8;

    return-object v2

    :pswitch_3
    check-cast p1, Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/UserTypeFactoryHook;->OooO0O0(Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_4
    check-cast p1, Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/UserTypeFactoryHook;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_5
    check-cast p1, Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/UserTypeFactoryHook;->OooO0o(Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_6
    check-cast p1, Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/UserTypeFactoryHook;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_7
    check-cast p1, Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/UserTypeFactoryHook;->OooO0OO(Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_8
    check-cast p1, Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/UserTypeFactoryHook;->OooO0Oo(Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_9
    check-cast p1, Llyiahf/vczjk/l48;

    const-string v0, "statement"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/gh8;

    invoke-direct {v0}, Llyiahf/vczjk/gh8;-><init>()V

    :goto_0
    invoke-interface {p1}, Llyiahf/vczjk/l48;->o000000()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {p1, v1}, Llyiahf/vczjk/l48;->getLong(I)J

    move-result-wide v2

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/gh8;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/gh8;->OooO0O0()Llyiahf/vczjk/gh8;

    move-result-object p1

    return-object p1

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/l48;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/l48;->o000000()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
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
