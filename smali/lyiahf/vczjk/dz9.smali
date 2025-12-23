.class public final Llyiahf/vczjk/dz9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pd1;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/cz9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cz9;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dz9;->OooO00o:Llyiahf/vczjk/cz9;

    invoke-interface {p1}, Llyiahf/vczjk/cz9;->OooO00o()Llyiahf/vczjk/bz9;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v0}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    invoke-interface {p1}, Llyiahf/vczjk/cz9;->OooO00o()Llyiahf/vczjk/bz9;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/dz9;->OooO00o:Llyiahf/vczjk/cz9;

    invoke-interface {v0}, Llyiahf/vczjk/cz9;->OooO00o()Llyiahf/vczjk/bz9;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0oo()J

    move-result-wide v0

    sget-object v2, Llyiahf/vczjk/vba;->OooO00o:Ljava/util/List;

    const v2, 0xf423f

    int-to-long v2, v2

    add-long/2addr v0, v2

    const v2, 0xf4240

    int-to-long v2, v2

    div-long/2addr v0, v2

    return-wide v0
.end method
