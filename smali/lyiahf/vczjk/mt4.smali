.class public final Llyiahf/vczjk/mt4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $index:I

.field final synthetic $itemProvider:Llyiahf/vczjk/nt4;

.field final synthetic $key:Ljava/lang/Object;

.field final synthetic $saveableStateHolder:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nt4;Ljava/lang/Object;ILjava/lang/Object;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mt4;->$itemProvider:Llyiahf/vczjk/nt4;

    iput-object p2, p0, Llyiahf/vczjk/mt4;->$saveableStateHolder:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/mt4;->$index:I

    iput-object p4, p0, Llyiahf/vczjk/mt4;->$key:Ljava/lang/Object;

    iput p5, p0, Llyiahf/vczjk/mt4;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/mt4;->$itemProvider:Llyiahf/vczjk/nt4;

    iget-object v1, p0, Llyiahf/vczjk/mt4;->$saveableStateHolder:Ljava/lang/Object;

    iget v2, p0, Llyiahf/vczjk/mt4;->$index:I

    iget-object v3, p0, Llyiahf/vczjk/mt4;->$key:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/mt4;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/l4a;->OooO0o(Llyiahf/vczjk/nt4;Ljava/lang/Object;ILjava/lang/Object;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
