.class public final synthetic Llyiahf/vczjk/fa2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ku5;Llyiahf/vczjk/tw8;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/fa2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fa2;->OooOOOO:Ljava/lang/Object;

    iput-boolean p3, p0, Llyiahf/vczjk/fa2;->OooOOO:Z

    iput-object p2, p0, Llyiahf/vczjk/fa2;->OooOOOo:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/ze3;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/fa2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fa2;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/fa2;->OooOOOo:Ljava/lang/Object;

    iput-boolean p3, p0, Llyiahf/vczjk/fa2;->OooOOO:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/String;Llyiahf/vczjk/gt8;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/fa2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/fa2;->OooOOO:Z

    iput-object p2, p0, Llyiahf/vczjk/fa2;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/fa2;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/fa2;->OooOOOO:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/fa2;->OooOOOo:Ljava/lang/Object;

    iget-boolean v3, p0, Llyiahf/vczjk/fa2;->OooOOO:Z

    iget v4, p0, Llyiahf/vczjk/fa2;->OooOOO0:I

    packed-switch v4, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/af8;

    if-eqz v3, :cond_0

    sget-object v3, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v3, Llyiahf/vczjk/ve8;->OooOO0:Llyiahf/vczjk/ze8;

    sget-object v4, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v5, 0x3

    aget-object v4, v4, v5

    new-instance v4, Llyiahf/vczjk/n25;

    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v3, p1, v4}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    :cond_0
    new-instance v3, Llyiahf/vczjk/jt8;

    check-cast v2, Llyiahf/vczjk/gt8;

    const/4 v4, 0x0

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/jt8;-><init>(Llyiahf/vczjk/gt8;I)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooOo0:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    const/4 v5, 0x0

    invoke-direct {v4, v5, v3}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/je8;

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    check-cast v1, Ljava/lang/String;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0o0(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    return-object v0

    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    xor-int/lit8 p1, v3, 0x1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    check-cast v1, Llyiahf/vczjk/ze3;

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-interface {v1, v2, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/qc2;

    new-instance p1, Llyiahf/vczjk/ga2;

    check-cast v1, Llyiahf/vczjk/ku5;

    check-cast v2, Llyiahf/vczjk/tw8;

    invoke-direct {p1, v1, v2, v3}, Llyiahf/vczjk/ga2;-><init>(Llyiahf/vczjk/ku5;Llyiahf/vczjk/tw8;Z)V

    iget-object v0, v1, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wy4;->OooO00o(Llyiahf/vczjk/ty4;)V

    new-instance v0, Llyiahf/vczjk/xb;

    const/4 v2, 0x2

    invoke-direct {v0, v2, v1, p1}, Llyiahf/vczjk/xb;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
