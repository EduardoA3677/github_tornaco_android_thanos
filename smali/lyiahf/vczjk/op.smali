.class public final synthetic Llyiahf/vczjk/op;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo:Llyiahf/vczjk/zy4;

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:Llyiahf/vczjk/fx9;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;FLlyiahf/vczjk/zy4;Llyiahf/vczjk/fx9;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/op;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/op;->OooOOO:Llyiahf/vczjk/hl5;

    iput-object p3, p0, Llyiahf/vczjk/op;->OooOOOO:Llyiahf/vczjk/a91;

    iput-object p4, p0, Llyiahf/vczjk/op;->OooOOOo:Llyiahf/vczjk/a91;

    iput p5, p0, Llyiahf/vczjk/op;->OooOOo0:F

    iput-object p6, p0, Llyiahf/vczjk/op;->OooOOo:Llyiahf/vczjk/zy4;

    iput-object p7, p0, Llyiahf/vczjk/op;->OooOOoo:Llyiahf/vczjk/fx9;

    iput p8, p0, Llyiahf/vczjk/op;->OooOo00:I

    iput p9, p0, Llyiahf/vczjk/op;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/op;->OooOo00:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-object v0, p0, Llyiahf/vczjk/op;->OooOOO0:Llyiahf/vczjk/a91;

    iget-object v6, p0, Llyiahf/vczjk/op;->OooOOoo:Llyiahf/vczjk/fx9;

    iget v9, p0, Llyiahf/vczjk/op;->OooOo0:I

    iget-object v1, p0, Llyiahf/vczjk/op;->OooOOO:Llyiahf/vczjk/hl5;

    iget-object v2, p0, Llyiahf/vczjk/op;->OooOOOO:Llyiahf/vczjk/a91;

    iget-object v3, p0, Llyiahf/vczjk/op;->OooOOOo:Llyiahf/vczjk/a91;

    iget v4, p0, Llyiahf/vczjk/op;->OooOOo0:F

    iget-object v5, p0, Llyiahf/vczjk/op;->OooOOo:Llyiahf/vczjk/zy4;

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/up;->OooO0o0(Llyiahf/vczjk/a91;Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;FLlyiahf/vczjk/zy4;Llyiahf/vczjk/fx9;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
