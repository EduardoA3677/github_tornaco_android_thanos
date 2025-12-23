.class public abstract Llyiahf/vczjk/eb0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yt5;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/fa4;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    sput-object v0, Llyiahf/vczjk/eb0;->OooOOO0:Llyiahf/vczjk/fa4;

    return-void
.end method


# virtual methods
.method public OooO()Llyiahf/vczjk/xn;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract OooO0O0()Llyiahf/vczjk/wa7;
.end method

.method public OooO0o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public OooO0o0()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOO0o()Llyiahf/vczjk/vm;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOOo()Llyiahf/vczjk/rm;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOOO()Llyiahf/vczjk/mm;

    move-result-object v0

    :cond_0
    if-eqz v0, :cond_1

    const/4 v0, 0x1

    return v0

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public abstract OooO0oO()Llyiahf/vczjk/fa4;
.end method

.method public OooO0oo()Llyiahf/vczjk/t66;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOO0()[Ljava/lang/Class;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOO0O()Llyiahf/vczjk/pm;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOOOO()Llyiahf/vczjk/rm;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOOO()Llyiahf/vczjk/mm;

    move-result-object v0

    :cond_0
    return-object v0
.end method

.method public abstract OooOO0o()Llyiahf/vczjk/vm;
.end method

.method public abstract OooOOO()Llyiahf/vczjk/mm;
.end method

.method public abstract OooOOO0()Ljava/util/Iterator;
.end method

.method public abstract OooOOOO()Llyiahf/vczjk/rm;
.end method

.method public abstract OooOOOo()Llyiahf/vczjk/x64;
.end method

.method public abstract OooOOo()Llyiahf/vczjk/rm;
.end method

.method public abstract OooOOo0()Ljava/lang/Class;
.end method

.method public abstract OooOOoo()Llyiahf/vczjk/xa7;
.end method

.method public abstract OooOo()Z
.end method

.method public abstract OooOo0()Z
.end method

.method public abstract OooOo00()Z
.end method

.method public abstract OooOo0O(Llyiahf/vczjk/xa7;)Z
.end method

.method public abstract OooOo0o()Z
.end method

.method public OooOoO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public abstract OooOoO0()Z
.end method

.method public abstract getFullName()Llyiahf/vczjk/xa7;
.end method
