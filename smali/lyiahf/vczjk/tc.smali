.class public final Llyiahf/vczjk/tc;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $onDismissRequest:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $properties:Llyiahf/vczjk/ab2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/ab2;Llyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tc;->$onDismissRequest:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/tc;->$properties:Llyiahf/vczjk/ab2;

    iput-object p3, p0, Llyiahf/vczjk/tc;->$content:Llyiahf/vczjk/ze3;

    iput p4, p0, Llyiahf/vczjk/tc;->$$changed:I

    iput p5, p0, Llyiahf/vczjk/tc;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/tc;->$onDismissRequest:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/tc;->$properties:Llyiahf/vczjk/ab2;

    iget-object v2, p0, Llyiahf/vczjk/tc;->$content:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/tc;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v4

    iget v5, p0, Llyiahf/vczjk/tc;->$$default:I

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/dn8;->OooOOo0(Llyiahf/vczjk/le3;Llyiahf/vczjk/ab2;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
