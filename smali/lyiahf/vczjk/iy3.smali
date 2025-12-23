.class public final Llyiahf/vczjk/iy3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $tmp2_rcvr:Llyiahf/vczjk/jy3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jy3;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/iy3;->$tmp2_rcvr:Llyiahf/vczjk/jy3;

    iput p2, p0, Llyiahf/vczjk/iy3;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/iy3;->$tmp2_rcvr:Llyiahf/vczjk/jy3;

    iget v0, p0, Llyiahf/vczjk/iy3;->$$changed:I

    or-int/lit8 v0, v0, 0x1

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v0

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/jy3;->OooO00o(ILlyiahf/vczjk/rf1;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
