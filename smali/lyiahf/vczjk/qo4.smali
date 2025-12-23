.class public final Llyiahf/vczjk/qo4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $config:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/ro4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qo4;->this$0:Llyiahf/vczjk/ro4;

    iput-object p2, p0, Llyiahf/vczjk/qo4;->$config:Llyiahf/vczjk/hl7;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/qo4;->this$0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, p0, Llyiahf/vczjk/qo4;->$config:Llyiahf/vczjk/hl7;

    iget-object v2, v0, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jl5;

    iget v2, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v2, v2, 0x8

    if-eqz v2, :cond_a

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    :goto_0
    if-eqz v0, :cond_a

    iget v2, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v2, v2, 0x8

    if-eqz v2, :cond_9

    const/4 v2, 0x0

    move-object v3, v0

    move-object v4, v2

    :goto_1
    if-eqz v3, :cond_9

    instance-of v5, v3, Llyiahf/vczjk/ne8;

    const/4 v6, 0x1

    if-eqz v5, :cond_2

    check-cast v3, Llyiahf/vczjk/ne8;

    invoke-interface {v3}, Llyiahf/vczjk/ne8;->OooOoo()Z

    move-result v5

    if-eqz v5, :cond_0

    new-instance v5, Llyiahf/vczjk/je8;

    invoke-direct {v5}, Llyiahf/vczjk/je8;-><init>()V

    iput-object v5, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iput-boolean v6, v5, Llyiahf/vczjk/je8;->OooOOOo:Z

    :cond_0
    invoke-interface {v3}, Llyiahf/vczjk/ne8;->o0ooOoO()Z

    move-result v5

    if-eqz v5, :cond_1

    iget-object v5, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/je8;

    iput-boolean v6, v5, Llyiahf/vczjk/je8;->OooOOOO:Z

    :cond_1
    iget-object v5, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/af8;

    invoke-interface {v3, v5}, Llyiahf/vczjk/ne8;->OooooO0(Llyiahf/vczjk/af8;)V

    goto :goto_4

    :cond_2
    iget v5, v3, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v5, v5, 0x8

    if-eqz v5, :cond_8

    instance-of v5, v3, Llyiahf/vczjk/m52;

    if-eqz v5, :cond_8

    move-object v5, v3

    check-cast v5, Llyiahf/vczjk/m52;

    iget-object v5, v5, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v7, 0x0

    :goto_2
    if-eqz v5, :cond_7

    iget v8, v5, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v8, v8, 0x8

    if-eqz v8, :cond_6

    add-int/lit8 v7, v7, 0x1

    if-ne v7, v6, :cond_3

    move-object v3, v5

    goto :goto_3

    :cond_3
    if-nez v4, :cond_4

    new-instance v4, Llyiahf/vczjk/ws5;

    const/16 v8, 0x10

    new-array v8, v8, [Llyiahf/vczjk/jl5;

    invoke-direct {v4, v8}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_4
    if-eqz v3, :cond_5

    invoke-virtual {v4, v3}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v3, v2

    :cond_5
    invoke-virtual {v4, v5}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_6
    :goto_3
    iget-object v5, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_2

    :cond_7
    if-ne v7, v6, :cond_8

    goto :goto_1

    :cond_8
    :goto_4
    invoke-static {v4}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v3

    goto :goto_1

    :cond_9
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_a
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
