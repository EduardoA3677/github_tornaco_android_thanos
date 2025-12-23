.class public final Llyiahf/vczjk/qv2;
.super Llyiahf/vczjk/rl6;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Ljava/lang/Object;

.field public final OooO0Oo:Ljava/lang/String;

.field public final OooO0o:Llyiahf/vczjk/hu3;

.field public final OooO0o0:Llyiahf/vczjk/lea;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/pp3;Llyiahf/vczjk/lea;)V
    .locals 0

    const-string p3, "value"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "verificationMode"

    invoke-static {p4, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qv2;->OooO0OO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qv2;->OooO0Oo:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/qv2;->OooO0o0:Llyiahf/vczjk/lea;

    new-instance p3, Llyiahf/vczjk/hu3;

    invoke-static {p1, p2}, Llyiahf/vczjk/rl6;->OooO(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string p2, "message"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p3, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    move-result-object p1

    const-string p2, "getStackTrace(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p2, 0x2

    invoke-static {p2, p1}, Llyiahf/vczjk/sy;->o0ooOOo(I[Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/StackTraceElement;

    invoke-interface {p1, p2}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/StackTraceElement;

    invoke-virtual {p3, p1}, Ljava/lang/Throwable;->setStackTrace([Ljava/lang/StackTraceElement;)V

    iput-object p3, p0, Llyiahf/vczjk/qv2;->OooO0o:Llyiahf/vczjk/hu3;

    return-void
.end method


# virtual methods
.method public final OooO0oO()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/qv2;->OooO0o0:Llyiahf/vczjk/lea;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_2

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eq v0, v1, :cond_1

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    return-object v2

    :cond_0
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/qv2;->OooO0OO:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/qv2;->OooO0Oo:Ljava/lang/String;

    invoke-static {v0, v1}, Llyiahf/vczjk/rl6;->OooO(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "message"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "pn8"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-object v2

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/qv2;->OooO0o:Llyiahf/vczjk/hu3;

    throw v0
.end method

.method public final OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;
    .locals 0

    return-object p0
.end method
