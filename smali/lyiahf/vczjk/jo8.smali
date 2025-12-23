.class public final Llyiahf/vczjk/jo8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic this$0:Llyiahf/vczjk/ko8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/ko8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jo8;->$placeable:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/jo8;->this$0:Llyiahf/vczjk/ko8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/nw6;

    iget-object v1, p0, Llyiahf/vczjk/jo8;->$placeable:Llyiahf/vczjk/ow6;

    iget-object p1, p0, Llyiahf/vczjk/jo8;->this$0:Llyiahf/vczjk/ko8;

    iget-object v4, p1, Llyiahf/vczjk/ko8;->Oooo0o0:Llyiahf/vczjk/io8;

    const/4 v2, 0x0

    const/4 v5, 0x4

    const/4 v3, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/nw6;->OooOO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;IILlyiahf/vczjk/oe3;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
