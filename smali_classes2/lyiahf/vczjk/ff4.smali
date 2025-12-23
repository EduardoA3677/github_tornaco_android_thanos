.class public abstract Llyiahf/vczjk/ff4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf4;
.implements Llyiahf/vczjk/gi4;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final OooOOO0:Llyiahf/vczjk/wm7;


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/cf4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    new-instance v0, Llyiahf/vczjk/cf4;

    const/4 v2, 0x1

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ff4;->OooOOO0:Llyiahf/vczjk/wm7;

    new-instance v0, Llyiahf/vczjk/cf4;

    const/4 v2, 0x2

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    new-instance v0, Llyiahf/vczjk/cf4;

    const/4 v2, 0x3

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    new-instance v0, Llyiahf/vczjk/cf4;

    const/4 v2, 0x4

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    sget-object v0, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v1, Llyiahf/vczjk/cf4;

    const/4 v2, 0x5

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ff4;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final varargs OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/ff4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v0

    invoke-interface {v0, p1}, Llyiahf/vczjk/so0;->OooO0Oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/hu3;

    invoke-direct {v0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    throw v0
.end method

.method public abstract OooOO0O()Llyiahf/vczjk/so0;
.end method

.method public abstract OooOO0o()Llyiahf/vczjk/yf4;
.end method

.method public abstract OooOOO()Llyiahf/vczjk/eo0;
.end method

.method public abstract OooOOO0()Llyiahf/vczjk/so0;
.end method

.method public final OooOOOO()Ljava/util/List;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ff4;->OooOOO0:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "invoke(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/List;

    return-object v0
.end method

.method public final OooOOOo()Z
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/bf4;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "<init>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ff4;->OooOO0o()Llyiahf/vczjk/yf4;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->isAnnotation()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public abstract OooOOo0()Z
.end method
