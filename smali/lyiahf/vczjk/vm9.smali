.class public final Llyiahf/vczjk/vm9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $keys:[Ljava/lang/Object;

.field final synthetic $tmp1_rcvr:Llyiahf/vczjk/zm9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zm9;[Ljava/lang/Object;Llyiahf/vczjk/oe3;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vm9;->$tmp1_rcvr:Llyiahf/vczjk/zm9;

    iput-object p2, p0, Llyiahf/vczjk/vm9;->$keys:[Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/vm9;->$block:Llyiahf/vczjk/oe3;

    iput p4, p0, Llyiahf/vczjk/vm9;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/vm9;->$tmp1_rcvr:Llyiahf/vczjk/zm9;

    iget-object v0, p0, Llyiahf/vczjk/vm9;->$keys:[Ljava/lang/Object;

    array-length v1, v0

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/vm9;->$block:Llyiahf/vczjk/oe3;

    iget v2, p0, Llyiahf/vczjk/vm9;->$$changed:I

    or-int/lit8 v2, v2, 0x1

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v2

    invoke-virtual {p2, v0, v1, p1, v2}, Llyiahf/vczjk/zm9;->OooO0O0([Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
