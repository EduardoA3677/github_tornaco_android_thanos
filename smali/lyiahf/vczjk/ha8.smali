.class public final Llyiahf/vczjk/ha8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $$this$scroll:Llyiahf/vczjk/lz5;

.field final synthetic $this_with:Llyiahf/vczjk/db8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lz5;Llyiahf/vczjk/db8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ha8;->$$this$scroll:Llyiahf/vczjk/lz5;

    iput-object p2, p0, Llyiahf/vczjk/ha8;->$this_with:Llyiahf/vczjk/db8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/ke2;

    iget-object v0, p0, Llyiahf/vczjk/ha8;->$$this$scroll:Llyiahf/vczjk/lz5;

    iget-object v1, p0, Llyiahf/vczjk/ha8;->$this_with:Llyiahf/vczjk/db8;

    iget-wide v2, p1, Llyiahf/vczjk/ke2;->OooO00o:J

    iget-object p1, v1, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v1, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-ne p1, v1, :cond_0

    invoke-static {v2, v3, v5, v4}, Llyiahf/vczjk/p86;->OooO00o(JFI)J

    move-result-wide v1

    goto :goto_0

    :cond_0
    const/4 p1, 0x2

    invoke-static {v2, v3, v5, p1}, Llyiahf/vczjk/p86;->OooO00o(JFI)J

    move-result-wide v1

    :goto_0
    check-cast v0, Llyiahf/vczjk/za8;

    invoke-virtual {v0, v4, v1, v2}, Llyiahf/vczjk/za8;->OooO00o(IJ)J

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
