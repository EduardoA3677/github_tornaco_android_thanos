.class public final Llyiahf/vczjk/ce;
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

.field final synthetic $expanded:Z

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $offset:J

.field final synthetic $onDismissRequest:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $properties:Llyiahf/vczjk/d07;

.field final synthetic $scrollState:Llyiahf/vczjk/z98;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/ce;->$expanded:Z

    iput-object p2, p0, Llyiahf/vczjk/ce;->$onDismissRequest:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/ce;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p4, p0, Llyiahf/vczjk/ce;->$offset:J

    iput-object p6, p0, Llyiahf/vczjk/ce;->$scrollState:Llyiahf/vczjk/z98;

    iput-object p7, p0, Llyiahf/vczjk/ce;->$properties:Llyiahf/vczjk/d07;

    iput-object p8, p0, Llyiahf/vczjk/ce;->$content:Llyiahf/vczjk/bf3;

    iput p9, p0, Llyiahf/vczjk/ce;->$$changed:I

    iput p10, p0, Llyiahf/vczjk/ce;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-boolean v0, p0, Llyiahf/vczjk/ce;->$expanded:Z

    iget-object v1, p0, Llyiahf/vczjk/ce;->$onDismissRequest:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/ce;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v3, p0, Llyiahf/vczjk/ce;->$offset:J

    iget-object v5, p0, Llyiahf/vczjk/ce;->$scrollState:Llyiahf/vczjk/z98;

    iget-object v6, p0, Llyiahf/vczjk/ce;->$properties:Llyiahf/vczjk/d07;

    iget-object v7, p0, Llyiahf/vczjk/ce;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/ce;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget v10, p0, Llyiahf/vczjk/ce;->$$default:I

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/ge;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
