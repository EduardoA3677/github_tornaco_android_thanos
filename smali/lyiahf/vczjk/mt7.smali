.class public final Llyiahf/vczjk/mt7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ot7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ot7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mt7;->this$0:Llyiahf/vczjk/ot7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/mt7;->this$0:Llyiahf/vczjk/ot7;

    iget-object v6, p1, Llyiahf/vczjk/ot7;->OooOOO:Llyiahf/vczjk/sd2;

    iget v2, p1, Llyiahf/vczjk/ot7;->OooO0o0:F

    float-to-double v2, v2

    iget p1, p1, Llyiahf/vczjk/ot7;->OooO0o:F

    float-to-double v4, p1

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/vt6;->OooOOOo(DDD)D

    move-result-wide v0

    invoke-interface {v6, v0, v1}, Llyiahf/vczjk/sd2;->OooO0oo(D)D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    return-object p1
.end method
