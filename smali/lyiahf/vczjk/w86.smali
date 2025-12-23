.class public final Llyiahf/vczjk/w86;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $this_measure:Llyiahf/vczjk/nf5;

.field final synthetic this$0:Llyiahf/vczjk/x86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x86;Llyiahf/vczjk/nf5;Llyiahf/vczjk/ow6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/w86;->this$0:Llyiahf/vczjk/x86;

    iput-object p2, p0, Llyiahf/vczjk/w86;->$this_measure:Llyiahf/vczjk/nf5;

    iput-object p3, p0, Llyiahf/vczjk/w86;->$placeable:Llyiahf/vczjk/ow6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/nw6;

    iget-object p1, p0, Llyiahf/vczjk/w86;->this$0:Llyiahf/vczjk/x86;

    iget-object p1, p1, Llyiahf/vczjk/x86;->OooOoOO:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/w86;->$this_measure:Llyiahf/vczjk/nf5;

    invoke-interface {p1, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u14;

    iget-wide v1, p1, Llyiahf/vczjk/u14;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/w86;->this$0:Llyiahf/vczjk/x86;

    iget-boolean p1, p1, Llyiahf/vczjk/x86;->OooOoo0:Z

    const-wide v3, 0xffffffffL

    const/16 v5, 0x20

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/w86;->$placeable:Llyiahf/vczjk/ow6;

    shr-long v5, v1, v5

    long-to-int v5, v5

    and-long/2addr v1, v3

    long-to-int v1, v1

    invoke-static {v0, p1, v5, v1}, Llyiahf/vczjk/nw6;->OooO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    goto :goto_0

    :cond_0
    move-wide v6, v1

    iget-object v1, p0, Llyiahf/vczjk/w86;->$placeable:Llyiahf/vczjk/ow6;

    shr-long v8, v6, v5

    long-to-int v2, v8

    and-long/2addr v3, v6

    long-to-int v3, v3

    const/4 v4, 0x0

    const/16 v5, 0xc

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/nw6;->OooOO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;IILlyiahf/vczjk/oe3;I)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
