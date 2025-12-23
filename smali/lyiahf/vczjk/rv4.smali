.class public final Llyiahf/vczjk/rv4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $measuredItemProvider:Llyiahf/vczjk/uv4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nv4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rv4;->$measuredItemProvider:Llyiahf/vczjk/uv4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/rv4;->$measuredItemProvider:Llyiahf/vczjk/uv4;

    iget-wide v1, v0, Llyiahf/vczjk/uv4;->OooO0OO:J

    invoke-virtual {v0, p1, v1, v2}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object p1

    return-object p1
.end method
