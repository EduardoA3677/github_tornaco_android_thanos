.class public final Llyiahf/vczjk/yb9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $clipIndicatorToPadding:Z

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $indicator:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $indicatorAlignment:Llyiahf/vczjk/o4;

.field final synthetic $indicatorPadding:Llyiahf/vczjk/bi6;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onRefresh:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $refreshTriggerDistance:F

.field final synthetic $state:Llyiahf/vczjk/jc9;

.field final synthetic $swipeEnabled:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jc9;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZFLlyiahf/vczjk/o4;Llyiahf/vczjk/bi6;Llyiahf/vczjk/df3;ZLlyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yb9;->$state:Llyiahf/vczjk/jc9;

    iput-object p2, p0, Llyiahf/vczjk/yb9;->$onRefresh:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/yb9;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p4, p0, Llyiahf/vczjk/yb9;->$swipeEnabled:Z

    iput p5, p0, Llyiahf/vczjk/yb9;->$refreshTriggerDistance:F

    iput-object p6, p0, Llyiahf/vczjk/yb9;->$indicatorAlignment:Llyiahf/vczjk/o4;

    iput-object p7, p0, Llyiahf/vczjk/yb9;->$indicatorPadding:Llyiahf/vczjk/bi6;

    iput-object p8, p0, Llyiahf/vczjk/yb9;->$indicator:Llyiahf/vczjk/df3;

    iput-boolean p9, p0, Llyiahf/vczjk/yb9;->$clipIndicatorToPadding:Z

    iput-object p10, p0, Llyiahf/vczjk/yb9;->$content:Llyiahf/vczjk/ze3;

    iput p11, p0, Llyiahf/vczjk/yb9;->$$changed:I

    iput p12, p0, Llyiahf/vczjk/yb9;->$$default:I

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

    iget-object v0, p0, Llyiahf/vczjk/yb9;->$state:Llyiahf/vczjk/jc9;

    iget-object v1, p0, Llyiahf/vczjk/yb9;->$onRefresh:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/yb9;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v3, p0, Llyiahf/vczjk/yb9;->$swipeEnabled:Z

    iget v4, p0, Llyiahf/vczjk/yb9;->$refreshTriggerDistance:F

    iget-object v5, p0, Llyiahf/vczjk/yb9;->$indicatorAlignment:Llyiahf/vczjk/o4;

    iget-object v6, p0, Llyiahf/vczjk/yb9;->$indicatorPadding:Llyiahf/vczjk/bi6;

    iget-object v7, p0, Llyiahf/vczjk/yb9;->$indicator:Llyiahf/vczjk/df3;

    iget-boolean v8, p0, Llyiahf/vczjk/yb9;->$clipIndicatorToPadding:Z

    iget-object v9, p0, Llyiahf/vczjk/yb9;->$content:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/yb9;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget v12, p0, Llyiahf/vczjk/yb9;->$$default:I

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/tn6;->OooO0OO(Llyiahf/vczjk/jc9;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZFLlyiahf/vczjk/o4;Llyiahf/vczjk/bi6;Llyiahf/vczjk/df3;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
