.class public final Llyiahf/vczjk/va9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $typeConverter:Llyiahf/vczjk/m1a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/m1a;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    iput-object p1, p0, Llyiahf/vczjk/va9;->$block:Llyiahf/vczjk/ze3;

    iput-object v0, p0, Llyiahf/vczjk/va9;->$typeConverter:Llyiahf/vczjk/m1a;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/fl;

    iget-object v0, p0, Llyiahf/vczjk/va9;->$block:Llyiahf/vczjk/ze3;

    iget-object v1, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/va9;->$typeConverter:Llyiahf/vczjk/m1a;

    check-cast v2, Llyiahf/vczjk/n1a;

    iget-object v2, v2, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object p1, p1, Llyiahf/vczjk/fl;->OooO0o:Llyiahf/vczjk/dm;

    invoke-interface {v2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {v0, v1, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
