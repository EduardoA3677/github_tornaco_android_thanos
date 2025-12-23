.class public final Llyiahf/vczjk/pn1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $contextMenuBuilderBlock:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onDismiss:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $state:Llyiahf/vczjk/eo1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eo1;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pn1;->$state:Llyiahf/vczjk/eo1;

    iput-object p2, p0, Llyiahf/vczjk/pn1;->$onDismiss:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/pn1;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p4, p0, Llyiahf/vczjk/pn1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    iput p5, p0, Llyiahf/vczjk/pn1;->$$changed:I

    iput p6, p0, Llyiahf/vczjk/pn1;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/pn1;->$state:Llyiahf/vczjk/eo1;

    iget-object v1, p0, Llyiahf/vczjk/pn1;->$onDismiss:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/pn1;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, p0, Llyiahf/vczjk/pn1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    iget p1, p0, Llyiahf/vczjk/pn1;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget v6, p0, Llyiahf/vczjk/pn1;->$$default:I

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/c6a;->OooO(Llyiahf/vczjk/eo1;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
