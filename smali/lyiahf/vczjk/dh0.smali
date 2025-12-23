.class public final Llyiahf/vczjk/dh0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $boxHeight:I

.field final synthetic $boxWidth:I

.field final synthetic $measurable:Llyiahf/vczjk/ef5;

.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $this_measure:Llyiahf/vczjk/nf5;

.field final synthetic this$0:Llyiahf/vczjk/fh0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/ef5;Llyiahf/vczjk/nf5;IILlyiahf/vczjk/fh0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dh0;->$placeable:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/dh0;->$measurable:Llyiahf/vczjk/ef5;

    iput-object p3, p0, Llyiahf/vczjk/dh0;->$this_measure:Llyiahf/vczjk/nf5;

    iput p4, p0, Llyiahf/vczjk/dh0;->$boxWidth:I

    iput p5, p0, Llyiahf/vczjk/dh0;->$boxHeight:I

    iput-object p6, p0, Llyiahf/vczjk/dh0;->this$0:Llyiahf/vczjk/fh0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/nw6;

    iget-object v1, p0, Llyiahf/vczjk/dh0;->$placeable:Llyiahf/vczjk/ow6;

    iget-object v2, p0, Llyiahf/vczjk/dh0;->$measurable:Llyiahf/vczjk/ef5;

    iget-object p1, p0, Llyiahf/vczjk/dh0;->$this_measure:Llyiahf/vczjk/nf5;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    iget v4, p0, Llyiahf/vczjk/dh0;->$boxWidth:I

    iget v5, p0, Llyiahf/vczjk/dh0;->$boxHeight:I

    iget-object p1, p0, Llyiahf/vczjk/dh0;->this$0:Llyiahf/vczjk/fh0;

    iget-object v6, p1, Llyiahf/vczjk/fh0;->OooO00o:Llyiahf/vczjk/o4;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/ch0;->OooO0O0(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ef5;Llyiahf/vczjk/yn4;IILlyiahf/vczjk/o4;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
