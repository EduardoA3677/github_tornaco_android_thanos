.class public final Llyiahf/vczjk/jh0;
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

.field final synthetic $contentAlignment:Llyiahf/vczjk/o4;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $propagateMinConstraints:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;ZLlyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jh0;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/jh0;->$contentAlignment:Llyiahf/vczjk/o4;

    iput-boolean p3, p0, Llyiahf/vczjk/jh0;->$propagateMinConstraints:Z

    iput-object p4, p0, Llyiahf/vczjk/jh0;->$content:Llyiahf/vczjk/bf3;

    iput p5, p0, Llyiahf/vczjk/jh0;->$$changed:I

    iput p6, p0, Llyiahf/vczjk/jh0;->$$default:I

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

    iget-object v0, p0, Llyiahf/vczjk/jh0;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/jh0;->$contentAlignment:Llyiahf/vczjk/o4;

    iget-boolean v2, p0, Llyiahf/vczjk/jh0;->$propagateMinConstraints:Z

    iget-object v3, p0, Llyiahf/vczjk/jh0;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/jh0;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget v6, p0, Llyiahf/vczjk/jh0;->$$default:I

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/dn8;->OooOOOo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;ZLlyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
