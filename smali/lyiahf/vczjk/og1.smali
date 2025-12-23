.class public final Llyiahf/vczjk/og1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ng1;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/sg1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sg1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/og1;->OooOOO0:Llyiahf/vczjk/sg1;

    return-void
.end method


# virtual methods
.method public final OooO0oo()Ljava/lang/Iterable;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/og1;->OooOOO0:Llyiahf/vczjk/sg1;

    iget-object v0, v0, Llyiahf/vczjk/sg1;->OooOOo:Llyiahf/vczjk/js8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/og1;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/og1;

    iget-object p1, p1, Llyiahf/vczjk/og1;->OooOOO0:Llyiahf/vczjk/sg1;

    iget-object v0, p0, Llyiahf/vczjk/og1;->OooOOO0:Llyiahf/vczjk/sg1;

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/og1;->OooOOO0:Llyiahf/vczjk/sg1;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    return v0
.end method
