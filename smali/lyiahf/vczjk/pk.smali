.class public final Llyiahf/vczjk/pk;
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

.field final synthetic $enter:Llyiahf/vczjk/ep2;

.field final synthetic $exit:Llyiahf/vczjk/ct2;

.field final synthetic $label:Ljava/lang/String;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $visible:Z


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/pk;->$visible:Z

    iput-object p2, p0, Llyiahf/vczjk/pk;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/pk;->$enter:Llyiahf/vczjk/ep2;

    iput-object p4, p0, Llyiahf/vczjk/pk;->$exit:Llyiahf/vczjk/ct2;

    iput-object p5, p0, Llyiahf/vczjk/pk;->$label:Ljava/lang/String;

    iput-object p6, p0, Llyiahf/vczjk/pk;->$content:Llyiahf/vczjk/bf3;

    iput p7, p0, Llyiahf/vczjk/pk;->$$changed:I

    iput p8, p0, Llyiahf/vczjk/pk;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-boolean v0, p0, Llyiahf/vczjk/pk;->$visible:Z

    iget-object v1, p0, Llyiahf/vczjk/pk;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/pk;->$enter:Llyiahf/vczjk/ep2;

    iget-object v3, p0, Llyiahf/vczjk/pk;->$exit:Llyiahf/vczjk/ct2;

    iget-object v4, p0, Llyiahf/vczjk/pk;->$label:Ljava/lang/String;

    iget-object v5, p0, Llyiahf/vczjk/pk;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/pk;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget v8, p0, Llyiahf/vczjk/pk;->$$default:I

    invoke-static/range {v0 .. v8}, Landroidx/compose/animation/OooO0O0;->OooO0Oo(ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
