.class public final Llyiahf/vczjk/p46;
.super Llyiahf/vczjk/pca;
.source "SourceFile"


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/p46;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/p46;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    return-void
.end method

.method public final OooO0o()Llyiahf/vczjk/gc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    if-eq p1, p0, :cond_1

    instance-of p1, p1, Llyiahf/vczjk/p46;

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    const/4 v0, 0x4

    return v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    return-object v0
.end method
