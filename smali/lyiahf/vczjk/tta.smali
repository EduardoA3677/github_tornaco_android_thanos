.class public final Llyiahf/vczjk/tta;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic this$0:Llyiahf/vczjk/uta;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/uta;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tta;->$placeable:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/tta;->this$0:Llyiahf/vczjk/uta;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/tta;->$placeable:Llyiahf/vczjk/ow6;

    iget-object v1, p0, Llyiahf/vczjk/tta;->this$0:Llyiahf/vczjk/uta;

    iget v1, v1, Llyiahf/vczjk/uta;->OooOoOO:F

    const/4 v2, 0x0

    invoke-virtual {p1, v0, v2, v2, v1}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
