.class public final Llyiahf/vczjk/oh5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $expandedStates:Llyiahf/vczjk/ss5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ss5;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $scrollState:Llyiahf/vczjk/z98;

.field final synthetic $transformOriginState:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oh5;->$expandedStates:Llyiahf/vczjk/ss5;

    iput-object p2, p0, Llyiahf/vczjk/oh5;->$transformOriginState:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/oh5;->$scrollState:Llyiahf/vczjk/z98;

    iput-object p4, p0, Llyiahf/vczjk/oh5;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p5, p0, Llyiahf/vczjk/oh5;->$content:Llyiahf/vczjk/bf3;

    iput p6, p0, Llyiahf/vczjk/oh5;->$$changed:I

    iput p7, p0, Llyiahf/vczjk/oh5;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/oh5;->$expandedStates:Llyiahf/vczjk/ss5;

    iget-object v1, p0, Llyiahf/vczjk/oh5;->$transformOriginState:Llyiahf/vczjk/qs5;

    iget-object v2, p0, Llyiahf/vczjk/oh5;->$scrollState:Llyiahf/vczjk/z98;

    iget-object v3, p0, Llyiahf/vczjk/oh5;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v4, p0, Llyiahf/vczjk/oh5;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/oh5;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget v7, p0, Llyiahf/vczjk/oh5;->$$default:I

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/th5;->OooO00o(Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
