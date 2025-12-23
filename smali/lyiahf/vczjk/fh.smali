.class public final Llyiahf/vczjk/fh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layoutNode:Llyiahf/vczjk/ro4;

.field final synthetic $this_run:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fh;->$this_run:Llyiahf/vczjk/nh;

    iput-object p2, p0, Llyiahf/vczjk/fh;->$layoutNode:Llyiahf/vczjk/ro4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object p1, p0, Llyiahf/vczjk/fh;->$this_run:Llyiahf/vczjk/nh;

    iget-object v0, p0, Llyiahf/vczjk/fh;->$layoutNode:Llyiahf/vczjk/ro4;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOO(Landroid/view/View;Llyiahf/vczjk/ro4;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
