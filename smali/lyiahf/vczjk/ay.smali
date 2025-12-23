.class public final Llyiahf/vczjk/ay;
.super Ljava/util/AbstractSet;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/hy;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hy;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ay;->OooOOO0:Llyiahf/vczjk/hy;

    invoke-direct {p0}, Ljava/util/AbstractSet;-><init>()V

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ey;

    iget-object v1, p0, Llyiahf/vczjk/ay;->OooOOO0:Llyiahf/vczjk/hy;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ey;-><init>(Llyiahf/vczjk/hy;)V

    return-object v0
.end method

.method public final size()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ay;->OooOOO0:Llyiahf/vczjk/hy;

    invoke-virtual {v0}, Llyiahf/vczjk/ao8;->size()I

    move-result v0

    return v0
.end method
