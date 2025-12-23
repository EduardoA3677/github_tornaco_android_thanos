.class public final Llyiahf/vczjk/pp4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $flingBehavior:Llyiahf/vczjk/o23;

.field final synthetic $horizontalArrangement:Llyiahf/vczjk/nx;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $overscrollEffect:Llyiahf/vczjk/qg6;

.field final synthetic $reverseLayout:Z

.field final synthetic $state:Llyiahf/vczjk/dw4;

.field final synthetic $userScrollEnabled:Z

.field final synthetic $verticalAlignment:Llyiahf/vczjk/n4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pp4;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/pp4;->$state:Llyiahf/vczjk/dw4;

    iput-object p3, p0, Llyiahf/vczjk/pp4;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-boolean p4, p0, Llyiahf/vczjk/pp4;->$reverseLayout:Z

    iput-object p5, p0, Llyiahf/vczjk/pp4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iput-object p6, p0, Llyiahf/vczjk/pp4;->$verticalAlignment:Llyiahf/vczjk/n4;

    iput-object p7, p0, Llyiahf/vczjk/pp4;->$flingBehavior:Llyiahf/vczjk/o23;

    iput-boolean p8, p0, Llyiahf/vczjk/pp4;->$userScrollEnabled:Z

    iput-object p9, p0, Llyiahf/vczjk/pp4;->$overscrollEffect:Llyiahf/vczjk/qg6;

    iput-object p10, p0, Llyiahf/vczjk/pp4;->$content:Llyiahf/vczjk/oe3;

    iput p11, p0, Llyiahf/vczjk/pp4;->$$changed:I

    iput p12, p0, Llyiahf/vczjk/pp4;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/pp4;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/pp4;->$state:Llyiahf/vczjk/dw4;

    iget-object v2, p0, Llyiahf/vczjk/pp4;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-boolean v3, p0, Llyiahf/vczjk/pp4;->$reverseLayout:Z

    iget-object v4, p0, Llyiahf/vczjk/pp4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iget-object v5, p0, Llyiahf/vczjk/pp4;->$verticalAlignment:Llyiahf/vczjk/n4;

    iget-object v6, p0, Llyiahf/vczjk/pp4;->$flingBehavior:Llyiahf/vczjk/o23;

    iget-boolean v7, p0, Llyiahf/vczjk/pp4;->$userScrollEnabled:Z

    iget-object v8, p0, Llyiahf/vczjk/pp4;->$overscrollEffect:Llyiahf/vczjk/qg6;

    iget-object v9, p0, Llyiahf/vczjk/pp4;->$content:Llyiahf/vczjk/oe3;

    iget p1, p0, Llyiahf/vczjk/pp4;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget v12, p0, Llyiahf/vczjk/pp4;->$$default:I

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/mc4;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
