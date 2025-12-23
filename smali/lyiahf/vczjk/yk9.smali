.class public final Llyiahf/vczjk/yk9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $density:Llyiahf/vczjk/f62;

.field final synthetic $magnifierSize$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f62;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yk9;->$density:Llyiahf/vczjk/f62;

    iput-object p2, p0, Llyiahf/vczjk/yk9;->$magnifierSize$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/ae2;

    iget-wide v0, p1, Llyiahf/vczjk/ae2;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/yk9;->$magnifierSize$delegate:Llyiahf/vczjk/qs5;

    iget-object v2, p0, Llyiahf/vczjk/yk9;->$density:Llyiahf/vczjk/f62;

    invoke-static {v0, v1}, Llyiahf/vczjk/ae2;->OooO0O0(J)F

    move-result v3

    invoke-interface {v2, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    invoke-static {v0, v1}, Llyiahf/vczjk/ae2;->OooO00o(J)F

    move-result v0

    invoke-interface {v2, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    int-to-long v1, v3

    const/16 v3, 0x20

    shl-long/2addr v1, v3

    int-to-long v3, v0

    const-wide v5, 0xffffffffL

    and-long/2addr v3, v5

    or-long v0, v1, v3

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
