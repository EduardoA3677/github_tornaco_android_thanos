.class public final Llyiahf/vczjk/u16;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $layerBlock:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u16;->$layerBlock:Llyiahf/vczjk/oe3;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/u16;->$layerBlock:Llyiahf/vczjk/oe3;

    sget-object v1, Llyiahf/vczjk/v16;->OoooOO0:Llyiahf/vczjk/ft7;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, v1, Llyiahf/vczjk/ft7;->OooOoO0:Llyiahf/vczjk/qj8;

    iget-wide v2, v1, Llyiahf/vczjk/ft7;->OooOoOO:J

    iget-object v4, v1, Llyiahf/vczjk/ft7;->OooOoo:Llyiahf/vczjk/yn4;

    iget-object v5, v1, Llyiahf/vczjk/ft7;->OooOoo0:Llyiahf/vczjk/f62;

    invoke-interface {v0, v2, v3, v4, v5}, Llyiahf/vczjk/qj8;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object v0

    iput-object v0, v1, Llyiahf/vczjk/ft7;->OooOooO:Llyiahf/vczjk/qqa;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
