.class public final Llyiahf/vczjk/nz9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $transition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nz9;->$transition:Llyiahf/vczjk/bz9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/nz9;->$transition:Llyiahf/vczjk/bz9;

    new-instance v0, Llyiahf/vczjk/lz9;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/lz9;-><init>(Llyiahf/vczjk/bz9;I)V

    return-object v0
.end method
