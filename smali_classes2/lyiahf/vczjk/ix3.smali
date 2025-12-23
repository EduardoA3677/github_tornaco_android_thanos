.class public final Llyiahf/vczjk/ix3;
.super Llyiahf/vczjk/g5a;
.source "SourceFile"


# instance fields
.field public final OooO0O0:[Llyiahf/vczjk/t4a;

.field public final OooO0OO:[Llyiahf/vczjk/z4a;

.field public final OooO0Oo:Z


# direct methods
.method public constructor <init>([Llyiahf/vczjk/t4a;[Llyiahf/vczjk/z4a;Z)V
    .locals 1

    const-string v0, "parameters"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "arguments"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ix3;->OooO0O0:[Llyiahf/vczjk/t4a;

    iput-object p2, p0, Llyiahf/vczjk/ix3;->OooO0OO:[Llyiahf/vczjk/z4a;

    iput-boolean p3, p0, Llyiahf/vczjk/ix3;->OooO0Oo:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ix3;->OooO0Oo:Z

    return v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;
    .locals 4

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p1

    instance-of v0, p1, Llyiahf/vczjk/t4a;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/t4a;

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    if-nez p1, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/t4a;->getIndex()I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/ix3;->OooO0O0:[Llyiahf/vczjk/t4a;

    array-length v3, v2

    if-ge v0, v3, :cond_2

    aget-object v2, v2, v0

    invoke-interface {v2}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v2

    invoke-interface {p1}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-static {v2, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/ix3;->OooO0OO:[Llyiahf/vczjk/z4a;

    aget-object p1, p1, v0

    return-object p1

    :cond_2
    :goto_1
    return-object v1
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ix3;->OooO0OO:[Llyiahf/vczjk/z4a;

    array-length v0, v0

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
