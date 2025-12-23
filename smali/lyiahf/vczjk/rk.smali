.class public final Llyiahf/vczjk/rk;
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

.field final synthetic $this_AnimatedVisibility:Llyiahf/vczjk/q31;

.field final synthetic $visible:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rk;->$this_AnimatedVisibility:Llyiahf/vczjk/q31;

    iput-boolean p2, p0, Llyiahf/vczjk/rk;->$visible:Z

    iput-object p3, p0, Llyiahf/vczjk/rk;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p4, p0, Llyiahf/vczjk/rk;->$enter:Llyiahf/vczjk/ep2;

    iput-object p5, p0, Llyiahf/vczjk/rk;->$exit:Llyiahf/vczjk/ct2;

    iput-object p6, p0, Llyiahf/vczjk/rk;->$label:Ljava/lang/String;

    iput-object p7, p0, Llyiahf/vczjk/rk;->$content:Llyiahf/vczjk/bf3;

    iput p8, p0, Llyiahf/vczjk/rk;->$$changed:I

    iput p9, p0, Llyiahf/vczjk/rk;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/rk;->$this_AnimatedVisibility:Llyiahf/vczjk/q31;

    iget-boolean v1, p0, Llyiahf/vczjk/rk;->$visible:Z

    iget-object v2, p0, Llyiahf/vczjk/rk;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, p0, Llyiahf/vczjk/rk;->$enter:Llyiahf/vczjk/ep2;

    iget-object v4, p0, Llyiahf/vczjk/rk;->$exit:Llyiahf/vczjk/ct2;

    iget-object v5, p0, Llyiahf/vczjk/rk;->$label:Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/rk;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/rk;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget v9, p0, Llyiahf/vczjk/rk;->$$default:I

    invoke-static/range {v0 .. v9}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
